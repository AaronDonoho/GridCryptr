
library(shiny)
library(digest)
library(DT)
library(dplyr)
library(yaml)
library(devtools)
# remotes::install_github("ropensci/cyphr", upgrade = FALSE)
library(cyphr)

# generate public key from private key
# k <- key_sodium(sodium::pubkey(charToRaw( [insert 32 char string] )))
# use public key like this
# public_key <- cyphr::key_sodium(charToRaw( [insert the result of message(rawToChar(public_key))]))

# to decrypt:
# cyphr::decrypt(read.csv("download_data"), key_sodium(sodium::pubkey(charToRaw( [the 32 char string from before] ))))

bytes <- c("ab", "d9", "fd", "9f", "44", "cc", "84", "12", "59", "b1", "34", "d9", "6c", "8d", "51", "f9", "2d", "37", "d1", "ab", "9a", "3a", "91", "bd", "93", "c9", "f3", "73", "95", "d6", "13", "12")

yaml <- read_yaml("./config")
public_key <- cyphr::key_sodium(as.raw(as.hexmode(bytes)))
salt <<- yaml$salt

ui <- fluidPage(
  fileInput("file1", "Choose a CSV file",
            multiple = FALSE,
            accept = c("text/csv",
                       "text/comma-separated-values,text/plain",
                       ".csv")),
  checkboxInput("header", "Does the file have column headers?", TRUE),
  dataTableOutput("table"),
  br(),
  uiOutput("column_selection"),
  uiOutput("cipher"),
  uiOutput("remove"),
  br(),
  uiOutput("download_file")
)

server <- function(input, output) {

  data <- reactiveValues(uploaded = data.frame())
  
  observeEvent(input$file1, {
    tryCatch(
      {
        data$uploaded <- read.csv(input$file1$datapath,
                        header = input$header,
                        stringsAsFactors = F)
      },
      error = function(e) {
        data$uploaded <- data.frame()
        stop(safeError(e))
      }
    )
  })
  
  output$table <- DT::renderDataTable(
    {
      req(!identical(data$uploaded , data.frame()))
      return(DT::datatable(data.frame(data$uploaded),
                           selection = list(target = 'column'),
                           rownames = NULL,
                           options = list(dom = 't', bSort = F)))
    }
  )
  
  output$column_selection <- renderUI({
    req(!identical(data$uploaded, data.frame()))
    checkboxGroupInput("column_selection", "Please select the columns to be changed", choices = colnames(data$uploaded))
  })
  
  output$cipher <- renderUI({
    req(!identical(data$uploaded, data.frame()))
    actionButton("cipher", "Cipher the selected columns")
  })
  
  output$remove <- renderUI({
    req(!identical(data$uploaded, data.frame()))
    actionButton("remove", "Remove the selected columns")
  })
  
  output$download_file <- renderUI({
    req(!identical(data$uploaded, data.frame()))
    downloadButton("download_data", label = "Download results")
  })
  
  output$download_data <- downloadHandler(
    filename = function() {
      paste('ciphered-', Sys.time(), '.csv', sep='')
    },
    content = function(con) {
      cyphr::encrypt(write.csv(data$uploaded, con, row.names = F), public_key)
      # write.csv(data$uploaded, con, row.names = F)
    }
  )
  
  observeEvent(input$cipher, {
    req(input$column_selection, salt)
    for (column_name in input$column_selection) {
      data$uploaded[,column_name] <- sapply(paste0(data$uploaded[,column_name], salt), digest, "sha256")
    }
  })

  observeEvent(input$remove, {
    req(input$column_selection)
    data$uploaded <- data$uploaded[,!names(data$uploaded) %in% input$column_selection]
  })
  
  observeEvent(once = T, ignoreNULL = F, eventExpr = data$uploaded, {
    if (is.null(salt)) {
      showModal(salt_modal())
    }
  })
  
  salt_modal <- function(failed = F) {
    modalDialog(
      textInput("user_salt", "Please enter at least 20 random characters. This will be used to help secure your data."),
      if (failed) {
        div(tags$b("Invalid entry. At least 20 characters required.", style = "color: red;"))
      },
      footer = tagList(
        actionButton("submit_salt", "Submit")
      )
    )
  }
  
  observeEvent(input$submit_salt, {
    if (nchar(input$user_salt) >= 20) {
      yaml::write_yaml(data.frame(salt = digest(input$user_salt, "sha256")), "./config")
      yaml <<- read_yaml("./config")
      salt <<- yaml$salt
      removeModal()
    } else {
      showModal(salt_modal(T))
    }
  })
}

shinyApp(ui = ui, server = server)

